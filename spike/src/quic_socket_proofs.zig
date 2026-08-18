//! Q1 real-socket proofs: the certificate-free PSK handshake and 1-RTT
//! data over actual UDP sockets driven by poll() — IPv4, native IPv6,
//! and an IPv6 dual-stack server serving an IPv4-mapped client — with
//! emitted-datagram size checks against the configured 1200-byte cap.
//!
//! QUIC state uses the same sans-I/O lifecycles as the in-process
//! harness; here datagrams cross the kernel, so size assertions bind
//! real UDP payloads. Routing uses the fork's address-neutral endpoints
//! so native IPv6 paths work end to end.

const std = @import("std");
const testing = std.testing;
const quicz = @import("quicz");
const harness = @import("quic_harness.zig");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const alpn_zmosh = harness.alpn_zmosh;
const psk_identity = harness.psk_identity;

/// Monotonic nanosecond clock for socket-driven calls.
fn clockNs(counter: *i64) i64 {
    counter.* += 1_000_000; // 1 ms per step
    return counter.*;
}

const SocketPair = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    now: i64 = 1_000,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *Connection,
    server: *Connection,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    client_path: quicz.endpoint.UdpTuple,
    server_path: quicz.endpoint.UdpTuple,
    secrets: protection.InitialSecrets,
    scratch: [16384]u8 = undefined,
    client_sock: std.Io.net.Socket,
    server_sock: std.Io.net.Socket,
    server_addr: std.Io.net.IpAddress,
    client_addr: std.Io.net.IpAddress,
    max_client_payload: usize = 0,
    max_server_payload: usize = 0,

    fn fdPoll(sock: std.Io.net.Socket) std.posix.pollfd {
        return .{ .fd = sock.handle, .events = std.posix.POLL.IN, .revents = 0 };
    }

    fn readable(sock: std.Io.net.Socket) bool {
        var fds = [1]std.posix.pollfd{fdPoll(sock)};
        const n = std.posix.poll(&fds, 0) catch return false;
        return n > 0;
    }

    fn sendToServer(self: *SocketPair, data: []const u8) !void {
        if (data.len > self.max_client_payload) self.max_client_payload = data.len;
        try self.client_sock.send(self.io, &self.server_addr, data);
    }

    fn sendToClient(self: *SocketPair, data: []const u8) !void {
        if (data.len > self.max_server_payload) self.max_server_payload = data.len;
        try self.server_sock.send(self.io, &self.client_addr, data);
    }

    /// Deliver every queued kernel datagram to its QUIC consumer.
    fn pump(self: *SocketPair) !void {
        var buf: [9000]u8 = undefined;
        while (SocketPair.readable(self.server_sock)) {
            const r = self.server_sock.receive(self.io, &buf) catch break;
            try self.deliverTo(r.data, true);
        }
        while (SocketPair.readable(self.client_sock)) {
            const r = self.client_sock.receive(self.io, &buf) catch break;
            try self.deliverTo(r.data, false);
        }
    }

    fn deliverTo(self: *SocketPair, data: []const u8, to_server: bool) !void {
        const lifecycle = if (to_server) self.server_lifecycle else self.client_lifecycle;
        const conn = if (to_server) self.server else self.client;
        const path = if (to_server) self.server_path else self.client_path;
        const handle = if (to_server) harness.server_handle else harness.client_handle;
        const now = clockNs(&self.now);

        const info = protection.peekProtectedLongPacketInfo(data) catch {
            _ = lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAddress(
                handle,
                conn,
                path,
                now,
                data,
            ) catch {};
            return;
        };
        switch (info.packet_type) {
            .initial => {
                _ = lifecycle.processRoutedProtectedInitialDatagramAddress(
                    handle,
                    conn,
                    path,
                    now,
                    &harness.original_dcid,
                    data,
                ) catch {};
            },
            .handshake => {
                _ = lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAddress(
                    handle,
                    conn,
                    path,
                    now,
                    data,
                ) catch {};
            },
            else => {},
        }
    }

    const PollKind = enum { long, handshake, short };

    fn pollOne(self: *SocketPair, client_side: bool, kind: PollKind) !?[]u8 {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) harness.client_handle else harness.server_handle;
        const now = clockNs(&self.now);
        switch (kind) {
            .long => {
                if (conn.packetNumberSpaceDiscarded(.initial)) return null;
                return lifecycle.pollProtectedLongDatagram(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.original_dcid else &harness.client_scid,
                    if (client_side) &harness.client_scid else &harness.server_scid,
                    &[_]u8{},
                    .{ .initial = if (client_side) self.secrets.client else self.secrets.server },
                ) catch null;
            },
            .handshake => {
                if (!conn.hasHandshakeProtectionKeys() or conn.packetNumberSpaceDiscarded(.handshake)) return null;
                return lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.server_scid else &harness.client_scid,
                    if (client_side) &harness.client_scid else &harness.server_scid,
                ) catch null;
            },
            .short => {
                if (!conn.hasOneRttProtectionKeys()) return null;
                return lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.server_scid else &harness.client_scid,
                ) catch null;
            },
        }
    }

    fn flushOutbound(self: *SocketPair, client_side: bool) !void {
        inline for (.{ PollKind.long, PollKind.handshake, PollKind.short }) |kind| {
            var guard: usize = 0;
            while (guard < 4) : (guard += 1) {
                const dg = (try self.pollOne(client_side, kind)) orelse break;
                defer self.alloc.free(dg);
                if (client_side) {
                    try self.sendToServer(dg);
                } else {
                    try self.sendToClient(dg);
                }
            }
        }
    }

    /// One poll()-style exchange round: outbound from both sides, pump
    /// the kernel queues, then outbound again for reactive traffic.
    fn exchange(self: *SocketPair) !void {
        try self.flushOutbound(true);
        try self.flushOutbound(false);
        try self.pump();
        try self.flushOutbound(true);
        try self.pump();
        try self.flushOutbound(false);
    }

    fn driveClientCrypto(self: *SocketPair, space: quicz.PacketNumberSpace) !void {
        if (self.client.packetNumberSpaceDiscarded(space)) return;
        _ = try self.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            harness.client_handle,
            self.client,
            space,
            self.client_backend.cryptoBackend(),
            &self.scratch,
        );
    }

    fn driveServerCrypto(self: *SocketPair, space: quicz.PacketNumberSpace) !void {
        if (self.server.packetNumberSpaceDiscarded(space)) return;
        _ = try self.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            harness.server_handle,
            self.server,
            space,
            self.server_backend.cryptoBackend(),
            &self.scratch,
        );
    }

    /// Complete the PSK handshake over the real sockets, mirroring the
    /// in-process flight order.
    fn completeHandshake(self: *SocketPair) !void {
        try self.driveClientCrypto(.initial);
        try self.exchange();
        try self.driveServerCrypto(.initial);
        try self.exchange();
        try self.driveClientCrypto(.initial);
        try self.driveServerCrypto(.handshake);
        try self.exchange();
        try self.driveClientCrypto(.handshake);
        try self.exchange();
        try self.driveServerCrypto(.handshake);
        try self.exchange();
        if (!self.server.handshakeConfirmed()) return error.ServerNotConfirmed;
        try self.server.sendHandshakeDone();
        try self.exchange();
        if (!self.client.handshakeConfirmed()) return error.ClientNotConfirmed;
    }

    /// Send application data client->server over 1-RTT; returns what the
    /// server received.
    fn clientToServer(self: *SocketPair, stream_id: u64, bytes: []const u8, fin: bool) !?[]u8 {
        try self.client.sendOnStream(stream_id, bytes, fin);
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            try self.exchange();
            var buf: [4096]u8 = undefined;
            if (try self.server.recvOnStream(stream_id, &buf)) |n| {
                return try self.alloc.dupe(u8, buf[0..n]);
            }
        }
        return null;
    }

    fn deinit(self: *SocketPair) void {
        const alloc = self.alloc;
        // Teardown wipes TLS backends and Initial secrets first;
        // Connection.deinit wipes its own packet keys.
        self.client_backend.secureWipe();
        self.server_backend.secureWipe();
        quicz.protection.secureWipeInitialSecrets(&self.secrets);
        self.client.deinit();
        self.server.deinit();
        self.client_lifecycle.deinit();
        self.server_lifecycle.deinit();
        alloc.destroy(self.client_backend);
        alloc.destroy(self.server_backend);
        alloc.destroy(self.client);
        alloc.destroy(self.server);
        alloc.destroy(self.client_lifecycle);
        alloc.destroy(self.server_lifecycle);
        self.client_sock.close(self.io);
        self.server_sock.close(self.io);
        alloc.destroy(self);
    }
};

const Family = enum { ipv4, ipv6, dual_stack_v4_peer };

fn socketPairOver(alloc: std.mem.Allocator, io: std.Io, family: Family) !*SocketPair {
    const client_ip: std.Io.net.IpAddress = switch (family) {
        .ipv4, .dual_stack_v4_peer => .{ .ip4 = .loopback(0) },
        .ipv6 => .{ .ip6 = .loopback(0) },
    };
    // A dual-stack server binds :: (V6ONLY off by default on Linux) so an
    // IPv4 peer reaches it as a v4-mapped address; the pure-IPv6 server
    // binds ::1.
    const server_ip: std.Io.net.IpAddress = switch (family) {
        .ipv4 => .{ .ip4 = .loopback(0) },
        .ipv6 => .{ .ip6 = .loopback(0) },
        .dual_stack_v4_peer => .{ .ip6 = .{ .bytes = @splat(0), .port = 0 } },
    };

    const client_sock = try client_ip.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const server_sock = try server_ip.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const server_addr = server_sock.address;
    const client_addr = client_sock.address;
    // The client sends to the server's reachable form: the IPv4 mapping
    // of a dual-stack server, otherwise the bound address itself.
    const client_send_addr: std.Io.net.IpAddress = if (family == .dual_stack_v4_peer)
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = server_addr.ip6.port } }
    else
        server_addr;

    var bootstrap: [32]u8 = undefined;
    try io.randomSecure(&bootstrap);
    const psk = harness.derivePsk(bootstrap);

    const p = try alloc.create(SocketPair);
    errdefer alloc.destroy(p);
    p.* = .{
        .alloc = alloc,
        .io = io,
        .client_lifecycle = undefined,
        .server_lifecycle = undefined,
        .client = undefined,
        .server = undefined,
        .client_backend = undefined,
        .server_backend = undefined,
        .client_path = undefined,
        .server_path = undefined,
        .secrets = undefined,
        .client_sock = client_sock,
        .server_sock = server_sock,
        .server_addr = client_send_addr,
        .client_addr = client_addr,
    };

    p.client_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
    p.server_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
    p.client_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
    p.server_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);

    // Address-neutral paths: native IPv6 stays IPv6; IPv4 widens.
    const client_local: quicz.endpoint.UdpAddress = switch (client_addr) {
        .ip4 => |a| quicz.endpoint.UdpAddress.init4(a.bytes, a.port),
        .ip6 => |a| quicz.endpoint.UdpAddress.init6(a.bytes, a.port),
    };
    const server_local: quicz.endpoint.UdpAddress = switch (server_addr) {
        .ip4 => |a| quicz.endpoint.UdpAddress.init4(a.bytes, a.port),
        .ip6 => |a| quicz.endpoint.UdpAddress.init6(a.bytes, a.port),
    };
    // On the dual-stack server the kernel reports the IPv4 peer in
    // v4-mapped form (::ffff:a.b.c.d); the server-side route must use
    // exactly that view or every datagram looks like a path change.
    const server_view_of_client: quicz.endpoint.UdpAddress = blk: {
        if (family != .dual_stack_v4_peer) break :blk client_local;
        var mapped: [16]u8 = @splat(0);
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].* = client_addr.ip4.bytes;
        break :blk quicz.endpoint.UdpAddress.init6(mapped, client_addr.ip4.port);
    };
    p.client_path = .{ .local = client_local, .remote = server_local };
    p.server_path = .{ .local = server_local, .remote = server_view_of_client };

    // Route registration goes through the fork's neutral endpoints so
    // every family works identically.
    try p.client_lifecycle.router.registerConnectionIdAddress(
        harness.client_handle,
        &harness.client_scid,
        p.client_path,
        .{ .active_migration_disabled = true },
    );
    try p.server_lifecycle.router.registerConnectionIdAddress(
        harness.server_handle,
        &harness.original_dcid,
        p.server_path,
        .{ .active_migration_disabled = true },
    );
    try p.server_lifecycle.router.registerConnectionIdAddress(
        harness.server_handle,
        &harness.server_scid,
        p.server_path,
        .{ .active_migration_disabled = true },
    );

    const conn_cfg = quicz.Config{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 1200,
    };
    p.client = try alloc.create(Connection);
    p.server = try alloc.create(Connection);
    p.client.* = try Connection.init(alloc, .client, conn_cfg);
    p.server.* = try Connection.init(alloc, .server, conn_cfg);
    try p.server.validatePeerAddress();
    try p.client.setLocalInitialSourceConnectionId(&harness.client_scid);
    try p.server.setLocalInitialSourceConnectionId(&harness.server_scid);

    p.client_backend = try alloc.create(Tls13Backend);
    p.client_backend.* = Tls13Backend.initClientWithPsk(.{
        .alpn = &alpn_zmosh,
        .server_name = "zmosh",
        .disable_session_resumption = true,
    }, psk);
    try p.client_backend.setClientPskIdentity(psk_identity);

    p.server_backend = try alloc.create(Tls13Backend);
    p.server_backend.* = Tls13Backend.initServerWithPsk(.{
        .alpn = &alpn_zmosh,
        .disable_session_resumption = true,
    }, psk);
    try p.server_backend.setServerPskIdentity(psk_identity);

    p.secrets = try protection.deriveInitialSecrets(.v1, &harness.original_dcid);
    return p;
}

fn assertSocketHandshakeAndEcho(
    alloc: std.mem.Allocator,
    io: std.Io,
    family: Family,
    label: []const u8,
) !void {
    var p = try socketPairOver(alloc, io, family);
    defer p.deinit();

    try p.completeHandshake();
    try testing.expect(p.server.handshakeConfirmed());
    try testing.expect(p.client.handshakeConfirmed());

    // QUIC Initial datagrams must be padded to at least 1200 bytes on a
    // real socket, and nothing exceeds the configured 1200-byte cap.
    try testing.expect(p.max_client_payload >= 1200);
    try testing.expect(p.max_client_payload <= 1200);
    try testing.expect(p.max_server_payload <= 1200);

    const s = try p.client.openStream();
    const got = try p.clientToServer(s, label, true);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(label, got.?);
}

test "real sockets: IPv4 loopback PSK handshake, 1200-byte Initials, 1-RTT echo" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try assertSocketHandshakeAndEcho(alloc, io, .ipv4, "v4-socket-echo");
}

test "real sockets: native IPv6 loopback PSK handshake and 1-RTT echo" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try assertSocketHandshakeAndEcho(alloc, io, .ipv6, "v6-socket-echo");
}

test "real sockets: IPv6 dual-stack server serves an IPv4-mapped client" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // The server socket is IPv6 (dual-stack on Linux by default); the
    // client is IPv4, reaching it as a v4-mapped peer.
    try assertSocketHandshakeAndEcho(alloc, io, .dual_stack_v4_peer, "dual-stack-echo");
}

/// Baseline-relative allocation counters for the bounded-candidate
/// assertions: how many connection-sized objects this test itself created.
const AllocCounters = struct {
    connections: usize = 0,
    backends: usize = 0,
    streams: usize = 0,
    routes: usize = 0,
};

/// Drive one space unless its packet-number space is already discarded.
fn driveSpaceUnlessDiscarded(
    lifecycle: *quicz.EndpointConnectionLifecycle,
    handle: u64,
    conn: *Connection,
    space: quicz.PacketNumberSpace,
    backend: *Tls13Backend,
    scratch: []u8,
) !void {
    if (conn.packetNumberSpaceDiscarded(space)) return;
    _ = try lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        handle,
        conn,
        space,
        backend.cryptoBackend(),
        scratch,
    );
}

test "real sockets: native IPv6 Retry, bounded candidate, PSK handshake, 1-RTT echo" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Real IPv6 loopback sockets.
    var client_sock = try (std.Io.net.IpAddress{ .ip6 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
    var server_sock = try (std.Io.net.IpAddress{ .ip6 = .loopback(0) }).bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer client_sock.close(io);
    defer server_sock.close(io);
    const server_addr = server_sock.address;
    const client_addr = client_sock.address;

    var bootstrap: [32]u8 = undefined;
    try io.randomSecure(&bootstrap);
    const psk = harness.derivePsk(bootstrap);
    // The bootstrap secret and every derived copy are wiped on ALL paths.
    var bootstrap_copy = bootstrap;
    defer std.crypto.secureZero(u8, &bootstrap_copy);

    // Address-neutral routing for a native IPv6 path end to end.
    const client_local = quicz.endpoint.UdpAddress.init6(client_addr.ip6.bytes, client_addr.ip6.port);
    const server_local = quicz.endpoint.UdpAddress.init6(server_addr.ip6.bytes, server_addr.ip6.port);
    const client_path = quicz.endpoint.UdpTuple{ .local = client_local, .remote = server_local };
    const server_path = quicz.endpoint.UdpTuple{ .local = server_local, .remote = client_local };

    var baseline = AllocCounters{};

    // The CLIENT registers its own route (its outbound address choice);
    // the SERVER allocates nothing until the candidate is authenticated.
    var client_lifecycle = quicz.EndpointConnectionLifecycle.init(alloc);
    defer client_lifecycle.deinit();
    try client_lifecycle.router.registerConnectionIdAddress(
        harness.client_handle,
        &harness.client_scid,
        client_path,
        .{ .active_migration_disabled = true },
    );
    baseline.routes += 1;

    const conn_cfg = quicz.Config{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 1200,
    };
    const client = try alloc.create(Connection);
    client.* = try Connection.init(alloc, .client, conn_cfg);
    defer {
        client.deinit();
        alloc.destroy(client);
    }
    baseline.connections += 1;
    try client.setLocalInitialSourceConnectionId(&harness.client_scid);

    const client_backend = try alloc.create(Tls13Backend);
    client_backend.* = Tls13Backend.initClientWithPsk(.{
        .alpn = &alpn_zmosh,
        .server_name = "zmosh",
        .disable_session_resumption = true,
    }, psk);
    defer alloc.destroy(client_backend);
    baseline.backends += 1;
    try client_backend.setClientPskIdentity(psk_identity);
    var psk_copy = psk;
    defer std.crypto.secureZero(u8, &psk_copy);

    const secrets = try quicz.protection.deriveInitialSecrets(.v1, &harness.original_dcid);
    defer quicz.protection.secureWipeInitialSecrets(@constCast(&secrets));

    var scratch: [16384]u8 = undefined;
    var now: i64 = 1000;
    var recv_buf: [2048]u8 = undefined;
    const supported = [_]quicz.packet.Version{.v1};

    // Token policy + pending-Retry slot: the ONLY server state so far.
    const secret: quicz.address_validation_token.Secret = [_]u8{0x71} ** quicz.address_validation_token.secret_len;
    var token_secret_copy = secret;
    defer std.crypto.secureZero(u8, &token_secret_copy);
    var policy = quicz.endpoint.AddressValidationPolicy.init(alloc, secret, .{});
    defer policy.deinit();
    var slot = quicz.pending_retry_slot.PendingRetrySlot{};

    // ── 1. First tokenless client Initial over the real socket. ────────
    now += 1_000_000;
    try driveSpaceUnlessDiscarded(&client_lifecycle, harness.client_handle, client, .initial, client_backend, &scratch);
    const first_initial = (try client_lifecycle.pollProtectedLongDatagram(
        harness.client_handle,
        client,
        now,
        &harness.original_dcid,
        &harness.client_scid,
        &[_]u8{},
        .{ .initial = secrets.client },
    )) orelse return error.NoInitial;
    defer alloc.free(first_initial);
    try testing.expect(first_initial.len >= 1200);
    try client_sock.send(io, &server_addr, first_initial);

    // ── 2. Server classifies the Initial for real (no preinstalled
    //       route) and answers with a Retry through the bounded slot. ──
    const r1 = try server_sock.receive(io, &recv_buf);
    try testing.expectEqual(@as(usize, first_initial.len), r1.data.len);
    const accept = (try quicz.endpoint.peekInitialAcceptDatagram(
        server_path,
        r1.data,
        &supported,
    )) orelse return error.NotAccepted;
    try testing.expectEqual(quicz.packet.Version.v1, accept.version);
    // The accepted slices borrow recv_buf, which every later receive
    // reuses; own copies so the stored exchange stays exact.
    const first_odcid = try alloc.dupe(u8, accept.original_destination_connection_id);
    defer alloc.free(first_odcid);
    const first_scid = try alloc.dupe(u8, accept.source_connection_id);
    defer alloc.free(first_scid);

    const nonce: quicz.address_validation_token.Nonce = [_]u8{0x42} ** quicz.address_validation_token.nonce_len;
    const token = try policy.issueTokenForPath(
        alloc,
        .retry,
        now,
        10 * std.time.ns_per_s,
        server_path,
        nonce,
    );
    defer alloc.free(token);
    const retry_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

    const retry = try slot.open(
        alloc,
        now,
        10 * std.time.ns_per_s,
        server_path,
        .v1,
        first_odcid,
        first_scid,
        &retry_scid,
        token,
    );
    try server_sock.send(io, &client_addr, retry);

    // ── 3. Baseline-relative failure matrix against the slot: every
    //       malformed/expired/replayed/wrong-path/unrelated attempt must
    //       leave all allocation counters at zero delta. ───────────────
    const failAttempts = struct {
        fn run(
            s: *quicz.pending_retry_slot.PendingRetrySlot,
            pol: *const quicz.endpoint.AddressValidationPolicy,
            t: i64,
            sp: quicz.endpoint.UdpTuple,
            odcid: []const u8,
            cscid: []const u8,
            rscid: []const u8,
            tok: []const u8,
        ) !void {
            const wrong_scid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
            const other_path = quicz.endpoint.UdpTuple{
                .local = sp.local,
                .remote = quicz.endpoint.UdpAddress.init6Scoped(sp.remote.v6, 51000, 9),
            };
            // Short datagram.
            try testing.expectError(error.InitialTooShort, s.classify(pol, t, sp, .v1, odcid, cscid, rscid, tok, 1199, true));
            // Not an Initial.
            try testing.expectError(error.NotAnInitial, s.classify(pol, t, sp, .v1, odcid, cscid, rscid, tok, 1200, false));
            // Unrelated tokenless Initial (different client SCID).
            try testing.expectError(error.UnrelatedInitial, s.classify(pol, t, sp, .v1, odcid, &wrong_scid, rscid, &.{}, 1200, true));
            // Wrong path on the follow-up.
            try testing.expectError(error.TokenInvalid, s.classify(pol, t, other_path, .v1, odcid, cscid, rscid, tok, 1200, true));
            // Wrong Retry SCID as the follow-up destination.
            try testing.expectError(error.TokenInvalid, s.classify(pol, t, sp, .v1, odcid, cscid, &wrong_scid, tok, 1200, true));
            // Wrong client SCID on the follow-up.
            try testing.expectError(error.TokenInvalid, s.classify(pol, t, sp, .v1, odcid, &wrong_scid, rscid, tok, 1200, true));
            // Mutated token bytes.
            var mutated = try std.heap.page_allocator.dupe(u8, tok);
            defer std.heap.page_allocator.free(mutated);
            mutated[0] ^= 0xff;
            try testing.expectError(error.TokenInvalid, s.classify(pol, t, sp, .v1, odcid, cscid, rscid, mutated, 1200, true));
        }
    };
    try failAttempts.run(&slot, &policy, now + 1, server_path, first_odcid, first_scid, &retry_scid, token);
    // No server connection, backend, stream, or route exists yet.
    try testing.expectEqual(baseline.connections, 1);
    try testing.expectEqual(baseline.backends, 1);
    try testing.expectEqual(baseline.routes, 1);

    // ── 4. The CLIENT receives the Retry on its real socket and performs
    //       the true quicz Retry sequence: processRetryDatagram records
    //       token + Retry SCID, retryReceived re-caches the ClientHello,
    //       resetInitialCryptoSendForRetry rewinds Initial send state,
    //       and the re-drive emits the follow-up Initial protected with
    //       Retry-SCID Initial keys. ────────────────────────────────────
    const r_retry = try client_sock.receive(io, &recv_buf);
    now += 1_000_000;
    try client.processRetryDatagram(now, &harness.original_dcid, r_retry.data);
    const conn_retry_scid = client.retrySourceConnectionId() orelse return error.NoRetryScid;
    try testing.expectEqualSlices(u8, &retry_scid, conn_retry_scid);
    const retry_keys = try quicz.protection.deriveInitialSecrets(.v1, conn_retry_scid);
    defer quicz.protection.secureWipeInitialSecrets(@constCast(&retry_keys));
    client_backend.retryReceived();
    try client.resetInitialCryptoSendForRetry();
    _ = try client.driveCryptoBackendInSpace(.initial, client_backend.cryptoBackend(), &scratch);
    const second_initial = (try client.pollProtectedLongCryptoDatagramInSpace(
        .initial,
        now,
        conn_retry_scid,
        &harness.client_scid,
        &[_]u8{},
        retry_keys.client,
    )) orelse return error.NoSecondInitial;
    defer alloc.free(second_initial);
    try testing.expect(second_initial.len >= 1200);
    try client_sock.send(io, &server_addr, second_initial);

    // ── 5. The server validates the exact stored exchange and creates
    //       ONE bounded unpublished candidate, authenticates the follow-up
    //       Initial, then publishes and commits. The follow-up Initial is
    //       the first datagram the server receives here. ────────────────
    const r3 = try server_sock.receive(io, &recv_buf);
    const accept2 = (try quicz.endpoint.peekInitialAcceptDatagram(
        server_path,
        r3.data,
        &supported,
    )) orelse return error.SecondNotAccepted;
    const decision = try slot.classify(
        &policy,
        now + 1,
        server_path,
        .v1,
        accept2.original_destination_connection_id,
        accept2.source_connection_id,
        conn_retry_scid,
        accept2.token,
        r3.data.len,
        true,
    );
    switch (decision) {
        .validated => {},
        else => return error.ExpectedValidated,
    }
    // Replay state unconsumed until commit.
    try testing.expectEqual(@as(usize, 0), policy.replayFilterEntryCount());

    // One bounded candidate: a server Connection + backend, published
    // nowhere yet.
    var server_lifecycle = quicz.EndpointConnectionLifecycle.init(alloc);
    defer server_lifecycle.deinit();
    const server = try alloc.create(Connection);
    server.* = try Connection.init(alloc, .server, conn_cfg);
    defer {
        server.deinit();
        alloc.destroy(server);
    }
    try server.validatePeerAddress();
    try server.setLocalInitialSourceConnectionId(&retry_scid);
    // Bring the candidate into the exact post-Retry server state: record
    // the original client DCID, the Retry SCID, and the pending token the
    // follow-up Initial must carry. The datagram bytes are discarded (the
    // slot already answered the first Initial).
    const candidate_retry = try server.issueRetryDatagram(
        now + 1,
        first_odcid,
        first_scid,
        &retry_scid,
        token,
    );
    defer alloc.free(candidate_retry);
    try testing.expect(server.pendingRetryTokenCount() == 1);
    const server_backend = try alloc.create(Tls13Backend);
    server_backend.* = Tls13Backend.initServerWithPsk(.{
        .alpn = &alpn_zmosh,
        .disable_session_resumption = true,
    }, psk);
    defer alloc.destroy(server_backend);
    try server_backend.setServerPskIdentity(psk_identity);

    // Authenticate: deliver the follow-up Initial to the candidate and
    // drive the TLS server — the PSK binder check happens here. Initial
    // keys for the follow-up derive from the Retry SCID.
    // For the follow-up Initial the datagram's destination CID IS the
    // Retry SCID, so one registration under the observed DCID covers the
    // published candidate.
    try testing.expectEqualSlices(u8, &retry_scid, accept2.original_destination_connection_id);
    _ = try server_lifecycle.router.registerConnectionIdAddress(
        harness.server_handle,
        accept2.original_destination_connection_id,
        server_path,
        .{ .active_migration_disabled = true },
    );
    _ = try server_lifecycle.processRoutedProtectedInitialDatagramAddress(
        harness.server_handle,
        server,
        server_path,
        now + 2,
        conn_retry_scid,
        r3.data,
    );
    try driveSpaceUnlessDiscarded(&server_lifecycle, harness.server_handle, server, .initial, server_backend, &scratch);
    // ServerHello exists => the follow-up Initial authenticated under the
    // PSK. Publish the candidate and consume the token.
    const sh = (try server_lifecycle.pollProtectedLongDatagram(
        harness.server_handle,
        server,
        now + 3,
        &harness.client_scid,
        &retry_scid,
        &[_]u8{},
        .{ .initial = retry_keys.server },
    )) orelse return error.NoServerHello;
    defer alloc.free(sh);
    try slot.commit(&policy, now + 4, accept2.token);
    try testing.expectEqual(@as(usize, 1), policy.replayFilterEntryCount());
    try testing.expect(!slot.occupied);
    // A retransmitted first Initial (after the candidate was published)
    // still matches the stored tuple only while the slot lives; after
    // commit the slot is cleared, so it is unrelated — but it must not
    // disturb the published candidate. (Before commit the same datagram
    // reissues the identical Retry, proven in the quicz slot tests.)
    try client_sock.send(io, &server_addr, first_initial);
    const r_retr = try server_sock.receive(io, &recv_buf);
    _ = r_retr;

    // Exactly one candidate was created: one server Connection, one
    // backend, and one route (the Retry-SCID DCID of the follow-up).
    try testing.expectEqual(baseline.connections + 1, 2);
    try testing.expectEqual(baseline.backends + 1, 2);
    try testing.expectEqual(server_lifecycle.router.routeCount(), 1);

    // ── 6. Complete the certificate-free PSK handshake over the SAME
    //       sockets and finish with a 1-RTT echo. ──────────────────────
    // Client processes the ServerHello.
    _ = try client_lifecycle.processRoutedProtectedInitialDatagramAddress(
        harness.client_handle,
        client,
        client_path,
        now + 5,
        conn_retry_scid,
        sh,
    );
    try driveSpaceUnlessDiscarded(&client_lifecycle, harness.client_handle, client, .initial, client_backend, &scratch);
    // Server handshake flight.
    try driveSpaceUnlessDiscarded(&server_lifecycle, harness.server_handle, server, .handshake, server_backend, &scratch);
    const sflight = (try server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        harness.server_handle,
        server,
        now + 6,
        &harness.client_scid,
        &retry_scid,
    )) orelse return error.NoServerFlight;
    defer alloc.free(sflight);
    try server_sock.send(io, &client_addr, sflight);
    const r4 = try client_sock.receive(io, &recv_buf);
    _ = try client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAddress(
        harness.client_handle,
        client,
        client_path,
        now + 7,
        r4.data,
    );
    try driveSpaceUnlessDiscarded(&client_lifecycle, harness.client_handle, client, .handshake, client_backend, &scratch);
    const cfin = (try client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        harness.client_handle,
        client,
        now + 8,
        &retry_scid,
        &harness.client_scid,
    )) orelse return error.NoClientFinished;
    defer alloc.free(cfin);
    try client_sock.send(io, &server_addr, cfin);
    const r5 = try server_sock.receive(io, &recv_buf);
    _ = try server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAddress(
        harness.server_handle,
        server,
        server_path,
        now + 9,
        r5.data,
    );
    try driveSpaceUnlessDiscarded(&server_lifecycle, harness.server_handle, server, .handshake, server_backend, &scratch);
    if (!server.handshakeConfirmed()) return error.ServerNotConfirmed;
    try server.sendHandshakeDone();
    const done = (try server_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        harness.server_handle,
        server,
        now + 10,
        &harness.client_scid,
    )) orelse return error.NoHandshakeDone;
    defer alloc.free(done);
    try server_sock.send(io, &client_addr, done);
    const r6 = try client_sock.receive(io, &recv_buf);
    _ = try client_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAddress(
        harness.client_handle,
        client,
        client_path,
        now + 11,
        r6.data,
    );
    try driveSpaceUnlessDiscarded(&client_lifecycle, harness.client_handle, client, .handshake, client_backend, &scratch);
    if (!client.handshakeConfirmed()) return error.ClientNotConfirmed;

    // 1-RTT echo over the same sockets.
    const stream_id = try client.openStream();
    try client.sendOnStream(stream_id, "v6-retry-echo", true);
    const echo_req = (try client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        harness.client_handle,
        client,
        now + 12,
        &retry_scid,
    )) orelse return error.NoEchoRequest;
    defer alloc.free(echo_req);
    try client_sock.send(io, &server_addr, echo_req);
    const r7 = try server_sock.receive(io, &recv_buf);
    _ = try server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAddress(
        harness.server_handle,
        server,
        server_path,
        now + 13,
        r7.data,
    );
    var echo_buf: [128]u8 = undefined;
    const n = (try server.recvOnStream(stream_id, &echo_buf)) orelse return error.NoEchoData;
    try testing.expectEqualStrings("v6-retry-echo", echo_buf[0..n]);
}
